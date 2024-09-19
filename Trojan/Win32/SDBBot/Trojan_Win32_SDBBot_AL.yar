
rule Trojan_Win32_SDBBot_AL{
	meta:
		description = "Trojan:Win32/SDBBot.AL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 1f 40 00 48 8b c2 83 e0 ?? 0f b6 0c 30 0f b6 84 15 fe 00 00 00 32 c8 88 8c 15 ?? ?? 00 00 48 ff c2 48 83 fa ?? 72 [0-40] 66 44 39 34 41 75 } //1
		$a_03_1 = {48 8b 44 24 30 48 8d 4d d0 48 83 c0 ?? ff d0 0f 10 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}