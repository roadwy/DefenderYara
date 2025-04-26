
rule Trojan_Win32_Tasker_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Tasker.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 ?? 89 45 fc 8b 4d fc 3b 4d 0c 7d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 55 fc 0f b6 02 83 f0 1e 8b 4d 08 03 4d fc 88 01 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}