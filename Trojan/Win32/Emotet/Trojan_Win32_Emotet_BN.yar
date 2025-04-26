
rule Trojan_Win32_Emotet_BN{
	meta:
		description = "Trojan:Win32/Emotet.BN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 2e 34 59 4d 34 71 68 43 7a 35 44 61 76 6e 43 6f 50 68 6a 6a 78 2e 70 64 62 } //1 r.4YM4qhCz5DavnCoPhjjx.pdb
		$a_01_1 = {62 00 72 00 65 00 48 00 45 00 52 00 56 00 57 00 72 00 6e 00 45 00 47 00 52 00 45 00 62 00 20 00 73 00 74 00 6f 00 70 00 20 00 7a 00 72 00 66 00 48 00 66 00 66 00 73 00 5a 00 47 00 65 00 48 00 20 00 5a 00 56 00 67 00 6c 00 74 00 64 00 6e 00 78 00 48 00 20 00 38 00 33 00 37 00 38 00 33 00 36 00 } //1 breHERVWrnEGREb stop zrfHffsZGeH ZVgltdnxH 837836
		$a_01_2 = {53 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 } //1 S Corpora
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}