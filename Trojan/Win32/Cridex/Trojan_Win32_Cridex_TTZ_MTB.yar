
rule Trojan_Win32_Cridex_TTZ_MTB{
	meta:
		description = "Trojan:Win32/Cridex.TTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {35 cd 5a 00 00 35 53 3a 00 00 89 45 ec 8b 55 f0 0f b6 02 8b 55 e8 88 02 ff 45 ?? 66 c7 45 e0 4b 00 66 83 7d e0 4d 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}