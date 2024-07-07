
rule Trojan_Win32_IcedID_PVB_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {30 36 57 59 70 34 4b 75 56 34 36 31 31 58 77 6a 71 48 64 69 75 42 31 6a 62 30 4a 4e 68 55 5a 4c 68 7a 55 51 36 56 34 4d 32 53 36 49 31 67 46 58 70 79 78 45 32 4d 51 42 66 4a 75 34 69 69 67 79 } //1 06WYp4KuV4611XwjqHdiuB1jb0JNhUZLhzUQ6V4M2S6I1gFXpyxE2MQBfJu4iigy
		$a_81_1 = {71 78 6e 56 58 35 59 52 6f 6e 69 61 35 4c 49 6b 6e 6b 4c 51 55 63 66 4c 4f 38 4e 59 76 6b 63 78 31 6d 6f 34 6e 73 31 56 48 30 79 } //1 qxnVX5YRonia5LIknkLQUcfLO8NYvkcx1mo4ns1VH0y
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}