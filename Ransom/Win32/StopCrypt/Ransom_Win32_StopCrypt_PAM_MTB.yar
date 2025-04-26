
rule Ransom_Win32_StopCrypt_PAM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 00 03 35 ef c6 c3 01 08 c3 55 8b ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}