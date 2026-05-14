
rule Trojan_Win32_Fugrafa_AH_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 45 44 59 45 46 4f 71 65 5a 4f 44 6c 43 46 4f 67 4b 5a 5a 43 44 4d 6b 6a } //20 iEDYEFOqeZODlCFOgKZZCDMkj
		$a_03_1 = {66 0f ef c2 0f 11 05 ?? ?? ?? ?? 0f 1f 44 00 00 80 b0 ?? ?? ?? ?? ?? 40 83 f8 ?? 72 } //30
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}