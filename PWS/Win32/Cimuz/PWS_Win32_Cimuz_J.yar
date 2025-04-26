
rule PWS_Win32_Cimuz_J{
	meta:
		description = "PWS:Win32/Cimuz.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 05 99 5b f7 fb 30 14 39 41 3b ce 72 f0 } //1
		$a_01_1 = {6a 05 5f 8d 34 01 8b c1 99 f7 ff 30 16 41 3b cb 72 eb } //1
		$a_01_2 = {52 54 5f 52 45 47 44 4c 4c 00 } //2 呒剟䝅䱄L
		$a_01_3 = {73 67 64 60 6c 6d 2c 67 68 6c 01 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=3
 
}