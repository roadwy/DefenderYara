
rule Ransom_Win32_StopCrypt_PAW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 00 47 86 c8 61 c3 [0-60] 81 00 f5 34 ef c6 c3 55 } //1
		$a_03_1 = {d3 eb c7 05 [0-04] 2e ce 50 91 89 45 ?? 03 [0-06] 33 d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}