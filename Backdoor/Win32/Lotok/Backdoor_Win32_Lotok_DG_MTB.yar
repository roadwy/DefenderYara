
rule Backdoor_Win32_Lotok_DG_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 d8 53 c6 45 d9 4f c6 45 da 46 c6 45 db 54 c6 45 dc 57 c6 45 dd 41 c6 45 de 52 c6 45 df 45 c6 45 e0 5c c6 45 e1 43 c6 45 e2 6c c6 45 e3 61 c6 45 e4 73 c6 45 e5 73 c6 45 e6 65 c6 45 e7 73 c6 45 e8 5c c6 45 e9 2e c6 45 ea 33 c6 45 eb 38 c6 45 ec 36 c6 45 ed 5c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}