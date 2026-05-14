
rule Trojan_Win64_Cobaltstrike_RR_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 84 24 80 00 00 00 7c c6 84 24 81 00 00 00 72 c6 84 24 82 00 00 00 65 c6 84 24 83 00 00 00 79 c6 84 24 84 00 00 00 72 c6 84 24 85 00 00 00 7b c6 84 24 86 00 00 00 24 c6 84 24 87 00 00 00 25 c6 84 24 88 00 00 00 39 c6 84 24 89 00 00 00 73 c6 84 24 8a 00 00 00 7b c6 84 24 8b 00 00 00 7b c6 84 24 8c 00 00 00 17 } //1
		$a_01_1 = {44 6c 6c 53 61 66 65 43 68 65 63 6b 36 34 } //1 DllSafeCheck64
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Cobaltstrike_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff98 00 ffffff98 00 05 00 00 "
		
	strings :
		$a_03_0 = {01 48 89 51 08 4c 8b 46 30 48 8b 46 38 44 8a 48 38 8a 40 39 88 44 24 20 48 8d 15 [0-05] e8 } //100
		$a_01_1 = {45 3a 5c 45 6e 76 5c 52 75 73 74 5c 2e 63 61 72 67 6f 5c 72 65 67 69 73 74 72 79 5c 73 72 63 5c 72 73 70 72 6f 78 79 2e 63 6e 2d 30 64 63 63 66 66 35 36 38 34 36 37 63 31 35 62 5c 61 65 73 2d 30 2e 38 2e 34 5c 73 72 63 5c 73 6f 66 74 5c 66 69 78 73 6c 69 63 65 36 34 2e 72 73 } //1 E:\Env\Rust\.cargo\registry\src\rsproxy.cn-0dccff568467c15b\aes-0.8.4\src\soft\fixslice64.rs
		$a_01_2 = {55 52 5a 47 58 54 2e 70 64 62 } //50 URZGXT.pdb
		$a_01_3 = {54 46 57 59 41 5a 2e 70 64 62 } //50 TFWYAZ.pdb
		$a_01_4 = {61 74 74 65 6d 70 74 20 74 6f 20 64 69 76 69 64 65 20 62 79 20 7a 65 72 6f } //1 attempt to divide by zero
	condition:
		((#a_03_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*50+(#a_01_3  & 1)*50+(#a_01_4  & 1)*1) >=152
 
}