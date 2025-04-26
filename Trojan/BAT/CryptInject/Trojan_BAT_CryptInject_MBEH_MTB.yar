
rule Trojan_BAT_CryptInject_MBEH_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {54 00 65 00 77 00 7a 00 72 00 62 00 76 00 76 00 6c 00 61 00 6c 00 72 00 6b 00 2e 00 53 00 66 00 79 00 64 00 6d 00 74 00 2e 00 64 00 6c 00 6c 00 00 17 51 00 76 00 67 00 65 00 77 00 6d 00 64 00 65 00 73 00 63 00 73 } //1
		$a_01_1 = {54 65 77 7a 72 62 76 76 6c 61 6c 72 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Tewzrbvvlalrk.Properties.Resources.resources
		$a_01_2 = {24 31 30 66 37 30 35 61 65 2d 37 33 32 36 2d 34 38 34 66 2d 38 66 64 63 2d 36 34 65 39 32 66 65 62 36 30 66 64 } //1 $10f705ae-7326-484f-8fdc-64e92feb60fd
		$a_01_3 = {43 6f 6e 73 6f 6c 65 41 70 70 31 33 2e 65 78 65 } //1 ConsoleApp13.exe
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}