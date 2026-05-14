
rule Trojan_Win64_SilverFox_AHB_MTB{
	meta:
		description = "Trojan:Win64/SilverFox.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 4e 43 52 45 41 53 49 4e 47 20 52 45 56 45 41 4c 20 53 54 4f 4f 44 20 56 41 4c 49 44 41 54 49 4f 4e 20 46 41 56 4f 55 52 49 54 45 00 00 00 00 } //30
		$a_01_1 = {63 6d 64 20 2f 76 20 2f 63 20 53 65 74 20 4a 6d 77 41 3d 63 6d 64 20 26 20 21 4a 6d 77 41 21 20 3c 20 50 61 73 73 69 76 65 2e 65 6d 6c } //20 cmd /v /c Set JmwA=cmd & !JmwA! < Passive.eml
		$a_03_2 = {26 8a 01 2c ?? 80 39 ?? 0f b6 d0 0f b6 01 0f 4c d0 44 0f be c2 41 8d 40 bf } //10
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20+(#a_03_2  & 1)*10) >=60
 
}