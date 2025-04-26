
rule Ransom_Win32_Genasom_AN{
	meta:
		description = "Ransom:Win32/Genasom.AN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 2f 5f 72 65 71 2f 3f 74 79 70 65 3d 25 63 26 73 69 64 3d 25 64 26 73 77 3d } //2 http://%s/_req/?type=%c&sid=%d&sw=
		$a_01_1 = {61 76 61 73 74 73 76 63 2e 65 78 65 } //1 avastsvc.exe
		$a_01_2 = {26 6f 73 74 79 70 65 3d 25 64 26 6f 73 73 70 3d 25 64 26 6f 73 62 69 74 73 3d 25 64 26 6f 73 66 77 74 79 70 65 3d 25 64 26 6f 73 72 69 67 68 74 73 3d } //3 &ostype=%d&ossp=%d&osbits=%d&osfwtype=%d&osrights=
		$a_01_3 = {73 75 70 70 6f 72 74 2e 6b 61 73 70 65 72 73 6b 79 2e 72 75 2f 76 69 72 75 73 65 73 2f 64 65 62 6c 6f 63 6b 65 72 } //3 support.kaspersky.ru/viruses/deblocker
		$a_01_4 = {50 43 20 48 65 61 6c 74 68 20 53 74 61 74 75 73 } //1 PC Health Status
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1) >=6
 
}