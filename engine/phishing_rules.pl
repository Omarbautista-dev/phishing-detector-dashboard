% ============================================================
% E6 · S06 — Motor de reglas de decisión (Phishing Detector)
% Pesos E2/S03: suma máxima 23. score = round(sum*100/23)
% Niveles: 0-24 segura | 25-55 sospechosa | 56-100 critica
% Regla extra: SI ip O arroba ENTONCES minimo sospechosa
% ============================================================

% --- Hechos: pesos por indicador (E2-marco-US03-pesos) ---
peso(ind_ip, 5).
peso(ind_arroba, 5).
peso(ind_sin_https, 3).
peso(ind_keywords, 3).
peso(ind_guion, 3).
peso(ind_larga, 2).
peso(ind_multisub, 2).
maximo(23).

% --- Hechos: indicadores detectados por URL (los genera el parser S07) ---
% ind('http://192.168.0.1/banco-seguro-login@fake.com/verify', ind_ip).
% ind(..., ind_sin_https). ind(..., ind_keywords). ind(..., ind_arroba).

% --- SI ... ENTONCES: reglas de nivel ---
nivel(S, critica)  :- S >= 56.
nivel(S, sospechosa) :- S >= 25, S < 56.
nivel(S, segura)   :- S < 25.

% --- SI ind_ip O ind_arroba ENTONCES minimo sospechosa ---
siempre_alerta(ind_ip).
siempre_alerta(ind_arroba).
alerta(URL) :- ind(URL, I), siempre_alerta(I).

% --- Motor: suma de pesos + score + nivel ---
sumar_pesos(URL, Suma) :-
    findall(P, (ind(URL, I), peso(I, P)), Ps),
    sumlist(Ps, Suma).

score(URL, Score) :-
    sumar_pesos(URL, Suma),
    maximo(Max),
    Score is round(Suma * 100 / Max).

riesgo(URL, Nivel, Score) :-
    score(URL, Score),
    nivel(Score, Nivel0),
    ( alerta(URL), Nivel0 = segura -> Nivel = sospechosa ; Nivel = Nivel0 ).

% --- Calibracion E2/S03 (casos de prueba) ---
% ?- riesgo('https://google.com', N, S).                    -> N=segura,   S=0
% ?- riesgo('http://192.168.0.1/banco-seguro-login@fake.com/verify', N, S).
%      hits: ip(5)+sin_https(3)+keywords(3)+arroba(5)=16 -> N=critica, S=70
% ?- riesgo('http://login-secure-update.ejemplo.largo.sub.dominio.com/verify/account/update/extra/path/datos/1234567890', N, S).
%      hits: larga(2)+multisub(2)+keywords(3)+sin_https(3)+guion(3)=13 -> N=critica, S=57
