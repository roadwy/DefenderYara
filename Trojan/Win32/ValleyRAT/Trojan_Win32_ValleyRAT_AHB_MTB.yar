
rule Trojan_Win32_ValleyRAT_AHB_MTB{
	meta:
		description = "Trojan:Win32/ValleyRAT.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 7a 79 2e 64 61 74 } //10 mzy.dat
		$a_01_1 = {4f 70 65 65 50 72 6f 63 64 73 73 61 6f 6b 65 6e } //20 OpeeProcdssaoken
		$a_03_2 = {f7 f1 0f b7 1c 55 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4f 75 ?? 8b c6 8b 4d f4 } //30
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_03_2  & 1)*30) >=60
 
}