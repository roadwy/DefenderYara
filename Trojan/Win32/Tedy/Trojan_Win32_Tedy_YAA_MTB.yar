
rule Trojan_Win32_Tedy_YAA_MTB{
	meta:
		description = "Trojan:Win32/Tedy.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 a8 2b d0 8b 45 ?? 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}