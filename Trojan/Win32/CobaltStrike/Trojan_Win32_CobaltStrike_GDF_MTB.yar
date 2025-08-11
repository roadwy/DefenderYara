
rule Trojan_Win32_CobaltStrike_GDF_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 89 45 ?? 89 65 ec 68 ?? ?? ?? ?? ff 75 fc 33 c0 ff 15 ?? ?? ?? ?? ?? ?? 39 65 ec } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}