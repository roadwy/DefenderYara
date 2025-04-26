
rule Trojan_Win32_Rootkit_GTL_MTB{
	meta:
		description = "Trojan:Win32/Rootkit.GTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {f0 d7 45 fb 86 4a fb f5 b0 c8 fd 29 a7 38 66 24 80 e2 31 59 a3 b2 e0 52 7e a2 40 6a 37 aa c8 c0 be b7 6c } //5
		$a_01_1 = {45 c4 50 51 56 56 56 56 ff 75 e4 6a 03 ff 15 20 e2 01 00 8b f8 89 7d 0c 3b fe 75 08 53 e8 af 43 00 00 eb 93 8b 75 18 33 c9 3b f1 74 74 51 51 51 56 ff } //5
		$a_01_2 = {5c 68 74 74 70 72 64 72 5c 74 64 78 66 6c 74 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 54 64 78 46 6c 74 5f 69 33 38 36 2e 70 64 62 } //1 \httprdr\tdxflt\objfre_wxp_x86\i386\TdxFlt_i386.pdb
		$a_01_3 = {45 78 41 63 71 75 69 72 65 46 61 73 74 4d 75 74 65 78 } //1 ExAcquireFastMutex
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}