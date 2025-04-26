
rule Trojan_Win32_TrickBot_DSX_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 04 0e 0f b6 d2 03 c2 99 f7 fb 8a 04 0a 8b 54 24 ?? 32 04 3a 88 07 } //1
		$a_81_1 = {2a 3f 4c 70 37 45 62 4f 38 37 42 7a 6d 4b 44 23 43 57 7a 40 68 46 41 6e 7d 75 4f 70 6d 75 7e 2a 77 4c 42 64 65 24 68 34 44 7d 74 30 31 5a 76 65 2a 6f 35 49 57 30 56 44 36 75 } //1 *?Lp7EbO87BzmKD#CWz@hFAn}uOpmu~*wLBde$h4D}t01Zve*o5IW0VD6u
		$a_81_2 = {34 37 79 6e 48 38 76 34 35 7a 48 7c 73 66 4d 73 3f 7a 7b 53 65 54 43 65 72 55 36 46 41 46 77 63 48 76 30 63 41 59 7a 70 41 78 48 54 4b 23 68 44 53 65 61 3f 4c 4c 78 52 4c 38 } //1 47ynH8v45zH|sfMs?z{SeTCerU6FAFwcHv0cAYzpAxHTK#hDSea?LLxRL8
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}