
rule Trojan_Win64_Tedy_SXH_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 05 00 00 "
		
	strings :
		$a_01_0 = {ff c7 48 83 c6 08 3b f9 7d 0a 48 8b 06 48 85 c0 48 0f 45 d8 ff c7 48 83 c6 08 3b f9 7c cc } //20
		$a_80_1 = {64 69 73 61 62 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 50 6f 6c 69 63 79 20 65 6e 66 6f 72 63 65 6d 65 6e 74 } //disable Execution Policy enforcement  2
		$a_80_2 = {64 69 73 61 62 6c 65 20 41 4d 53 49 } //disable AMSI  2
		$a_80_3 = {64 69 73 61 62 6c 65 20 45 54 57 20 50 72 6f 76 69 64 65 72 } //disable ETW Provider  2
		$a_80_4 = {50 4f 57 45 52 53 48 45 4c 4c 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 20 53 54 52 45 41 4d } //POWERSHELL INFORMATION STREAM  1
	condition:
		((#a_01_0  & 1)*20+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1) >=27
 
}