
rule Trojan_BAT_CryptInject_RHAK_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.RHAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 08 00 00 52 03 00 00 08 00 00 00 00 00 00 fe 70 03 } //2
		$a_00_1 = {72 00 75 00 62 00 62 00 65 00 72 00 70 00 61 00 72 00 74 00 73 00 6d 00 61 00 6e 00 75 00 66 00 61 00 63 00 74 00 75 00 72 00 65 00 72 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 68 00 75 00 6e 00 7a 00 69 00 71 00 2f 00 45 00 6f 00 64 00 6e 00 75 00 69 00 77 00 69 00 6f 00 2e 00 6d 00 70 00 34 00 } //3 rubberpartsmanufacturers.com/hunziq/Eodnuiwio.mp4
		$a_00_2 = {5a 00 6d 00 6b 00 77 00 72 00 72 00 61 00 2e 00 65 00 78 00 65 00 } //2 Zmkwrra.exe
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*3+(#a_00_2  & 1)*2) >=7
 
}