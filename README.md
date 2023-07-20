# AMSI_Patcher
Thanks to @D1rkMtr for the technique of using `jne` from amsi!AmsiOpenSession. I have used his AMSI patch code template and added other methods. This script skips entering amsi!AmsiOpenSession+0x4c via `ret`, by directly pasting `c3` at the beginning of the amsi!AmsiOpenSession. As a result, we end up directly at amsi!AmsiCloseSession.

![image](https://github.com/Gurpreet06/AMSI_Patcher/assets/74554439/675eef88-96d9-4e84-a63d-13859353c209)
