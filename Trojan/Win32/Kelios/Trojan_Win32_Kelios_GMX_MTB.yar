
rule Trojan_Win32_Kelios_GMX_MTB{
	meta:
		description = "Trojan:Win32/Kelios.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 57 ff c1 48 89 6c 34 ?? 49 c1 ff ?? 42 31 8c fc ?? ?? ?? ?? 5f 48 33 d2 44 8b ea 5d 45 8b c7 4a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}