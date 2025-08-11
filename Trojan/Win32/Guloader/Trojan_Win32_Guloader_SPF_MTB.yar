
rule Trojan_Win32_Guloader_SPF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_81_0 = {55 6e 73 61 6c 75 62 72 69 6f 75 73 6c 79 2e 6a 70 67 } //2 Unsalubriously.jpg
		$a_01_1 = {6b 00 6e 00 68 00 6a 00 65 00 5c 00 68 00 79 00 70 00 6f 00 68 00 79 00 61 00 6c 00 } //2 knhje\hypohyal
		$a_81_2 = {54 6f 72 75 6d 73 6c 65 6a 6c 69 67 68 65 64 65 72 73 5c 70 6f 6e 74 61 6c } //1 Torumslejligheders\pontal
		$a_81_3 = {62 65 74 61 74 72 6f 6e 73 2e 74 69 64 } //1 betatrons.tid
		$a_81_4 = {63 6f 65 6d 70 74 69 76 65 2e 62 72 69 } //1 coemptive.bri
		$a_81_5 = {6f 62 6a 65 6b 74 69 76 69 73 65 72 69 6e 67 65 72 73 2e 74 78 74 } //1 objektiviseringers.txt
		$a_81_6 = {53 63 6f 72 65 62 6f 61 72 64 73 5c 46 6f 72 73 6b 79 64 6e 69 6e 67 65 72 73 } //1 Scoreboards\Forskydningers
		$a_81_7 = {73 6f 6f 74 68 73 61 77 2e 61 66 73 } //1 soothsaw.afs
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=10
 
}