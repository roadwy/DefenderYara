
rule Trojan_Win64_Injector_SXH_MTB{
	meta:
		description = "Trojan:Win64/Injector.SXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 20 40 00 00 00 44 8b 46 50 48 8b 56 30 ff 15 ?? ?? ?? ?? 4c 8b f8 48 85 c0 75 07 33 ff ?? ?? ?? ?? ?? 44 8b 4e 54 45 33 ed 48 8b 4c 24 50 4c 8b c3 49 8b d7 4c 89 6c 24 20 ff 15 ?? ?? ?? ?? 85 c0 } //10
		$a_01_1 = {54 61 72 67 65 74 20 70 72 6f 63 65 73 73 20 69 73 20 33 32 2d 62 69 74 3a 20 25 73 } //5 Target process is 32-bit: %s
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 73 63 6f 70 65 64 5f 64 69 72 } //20 C:\Users\%s\AppData\Local\Temp\scoped_dir
		$a_01_3 = {53 6f 75 72 63 65 33 32 3a 20 25 73 2c 20 54 61 72 67 65 74 33 32 3a 20 25 73 } //5 Source32: %s, Target32: %s
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*20+(#a_01_3  & 1)*5) >=40
 
}