
rule Trojan_BAT_Fsysna_NS_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_1 = {54 47 47 37 75 31 4e 34 51 39 59 66 30 38 4e 46 } //1 TGG7u1N4Q9Yf08NF
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {74 73 72 31 53 74 30 59 35 37 78 59 56 75 32 38 } //1 tsr1St0Y57xYVu28
		$a_01_5 = {52 00 6f 00 62 00 6c 00 6f 00 78 00 2e 00 65 00 78 00 65 00 } //1 Roblox.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}