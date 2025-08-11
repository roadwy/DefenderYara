
rule Trojan_Win32_Rhadamanthys_GVA_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {ec 8b c5 eb } //2
		$a_02_1 = {8b 4c 24 38 33 cc e8 ?? ?? ?? ?? 83 c4 48 } //1
		$a_01_2 = {8b cd eb 02 8b 09 eb 02 } //1
		$a_01_3 = {0f be 08 eb 03 } //1
		$a_01_4 = {0f 9d c2 4a 8b c2 } //1
		$a_01_5 = {88 0a e9 98 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}