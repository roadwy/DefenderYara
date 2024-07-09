
rule Trojan_BAT_Dnoper_AL_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 27 00 00 70 0a 06 28 ?? ?? ?? 0a 0d 00 17 73 1d 00 00 0a 72 53 00 00 70 6f ?? ?? ?? 0a 13 04 09 11 04 16 11 04 8e 69 6f } //2
		$a_01_1 = {50 00 4c 00 55 00 47 00 47 00 20 00 4c 00 4f 00 43 00 4b 00 } //1 PLUGG LOCK
		$a_01_2 = {63 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 2e 00 62 00 61 00 74 00 } //1 c:\Windows\module.bat
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}