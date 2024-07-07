
rule Ransom_Win32_StopCrypt_PAW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 00 47 86 c8 61 c3 90 02 60 81 00 f5 34 ef c6 c3 55 90 00 } //1
		$a_03_1 = {d3 eb c7 05 90 02 04 2e ce 50 91 89 45 90 01 01 03 90 02 06 33 d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}