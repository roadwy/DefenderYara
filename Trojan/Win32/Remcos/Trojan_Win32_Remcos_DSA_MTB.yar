
rule Trojan_Win32_Remcos_DSA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b 75 0c 7c 90 09 06 00 ff 15 } //1
		$a_02_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 90 09 05 00 a1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}