
rule Trojan_Win64_CymulateRansomTest_MKD_MTB{
	meta:
		description = "Trojan:Win64/CymulateRansomTest.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 e8 48 81 c0 b8 00 00 00 48 c7 c1 0b 06 00 00 48 c7 c2 ?? ?? ?? ?? 30 10 48 ff c0 48 ff c9 0f 85 } //1
		$a_00_1 = {65 6e 63 72 79 70 74 69 6f 6e 5f 70 61 74 68 3a 73 74 72 69 6e 67 3a 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 63 79 6d 75 6c 61 74 65 5c 45 44 52 } //1 encryption_path:string:c:\programdata\cymulate\EDR
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}