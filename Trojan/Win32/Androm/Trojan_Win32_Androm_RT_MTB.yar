
rule Trojan_Win32_Androm_RT_MTB{
	meta:
		description = "Trojan:Win32/Androm.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {69 4f 25 57 4c 31 6e 4e 2a 58 4c 37 6b 46 31 73 42 31 71 52 31 57 45 48 65 46 43 6d 4a 39 70 4a 43 } //1 iO%WL1nN*XL7kF1sB1qR1WEHeFCmJ9pJC
		$a_81_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 73 6e 62 63 2e 63 6f 6d 2f 77 69 7a 2f } //1 http://www.ssnbc.com/wiz/
		$a_81_2 = {41 6c 61 73 73 65 73 5c 57 4f 57 36 34 33 32 4e 6f 64 65 5c 43 4c 53 } //1 Alasses\WOW6432Node\CLS
		$a_81_3 = {32 63 34 39 66 38 30 30 2d 63 32 64 64 2d 31 31 63 66 2d 39 61 64 36 2d 30 30 38 30 63 37 65 37 62 37 38 64 } //1 2c49f800-c2dd-11cf-9ad6-0080c7e7b78d
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}