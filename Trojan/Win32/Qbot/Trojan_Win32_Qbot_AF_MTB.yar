
rule Trojan_Win32_Qbot_AF_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 5c 31 66 5c 6f 75 74 5c 62 69 6e 61 72 69 65 73 5c 78 38 36 72 65 74 5c 62 69 6e 5c 69 33 38 36 5c 47 72 61 70 68 69 63 73 5c 64 78 74 65 78 2e 70 64 62 } //1 cmd\1f\out\binaries\x86ret\bin\i386\Graphics\dxtex.pdb
		$a_01_1 = {00 58 4c 35 35 00 } //1 堀㕌5
		$a_01_2 = {00 52 6f 61 64 46 72 6f 6d 46 69 6c 65 49 6e 4d 65 6d 6f 72 79 00 } //1 刀慯䙤潲䙭汩䥥䵮浥牯y
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}