
rule Trojan_Win32_Mikey_PGMY_MTB{
	meta:
		description = "Trojan:Win32/Mikey.PGMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 31 37 38 2e 31 36 2e 35 34 2e 31 30 39 2f 78 6d 72 69 67 2e 65 78 65 } //http://178.16.54.109/xmrig.exe  5
		$a_80_1 = {2f 63 20 25 73 20 2d 6f 20 31 37 38 2e 31 36 2e 35 34 2e 31 30 39 3a 36 30 36 30 20 2d 75 20 38 33 68 39 6d 42 76 79 31 4c 4c 32 71 57 36 63 32 48 65 57 63 7a 59 56 4a 51 73 46 44 46 37 52 66 56 71 44 6e 61 69 53 66 46 42 64 44 63 78 66 79 4a 66 57 68 52 6e 5a 71 5a 6b 59 35 63 68 62 35 62 36 74 6d 4b 5a 31 50 50 68 75 51 62 4e 67 58 67 67 43 64 77 54 72 4d 59 57 4e 38 68 69 } ///c %s -o 178.16.54.109:6060 -u 83h9mBvy1LL2qW6c2HeWczYVJQsFDF7RfVqDnaiSfFBdDcxfyJfWhRnZqZkY5chb5b6tmKZ1PPhuQbNgXggCdwTrMYWN8hi  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}