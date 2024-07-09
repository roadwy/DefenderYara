
rule Trojan_Win32_Injuke_RH_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 33 83 ff 0f 75 12 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7 7c b9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}