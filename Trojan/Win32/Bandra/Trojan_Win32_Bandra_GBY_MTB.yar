
rule Trojan_Win32_Bandra_GBY_MTB{
	meta:
		description = "Trojan:Win32/Bandra.GBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 8b 00 89 45 f4 69 45 f4 ?? ?? ?? ?? 89 45 f4 8b 45 f4 c1 e8 18 33 45 f4 89 45 f4 69 45 f4 ?? ?? ?? ?? 89 45 f4 69 45 fc ?? ?? ?? ?? 89 45 fc 8b 45 fc 33 45 f4 89 45 fc 8b 45 ec 83 c0 04 89 45 ec 8b 45 0c 83 e8 04 89 45 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}