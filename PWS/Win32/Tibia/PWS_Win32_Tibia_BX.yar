
rule PWS_Win32_Tibia_BX{
	meta:
		description = "PWS:Win32/Tibia.BX,SIGNATURE_TYPE_PEHSTR,67 00 67 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 69 62 69 61 6b 65 79 6c 6f 67 67 65 72 } //100 tibiakeylogger
		$a_01_1 = {26 69 64 65 6e 74 79 66 69 6b 61 74 6f 72 3d } //1 &identyfikator=
		$a_01_2 = {26 61 63 63 3d } //1 &acc=
		$a_01_3 = {26 70 61 73 73 3d } //1 &pass=
		$a_01_4 = {74 69 62 69 61 69 6e 6a 65 63 74 2e 70 6c } //1 tibiainject.pl
		$a_01_5 = {64 6f 64 61 6a 2e 70 68 70 3f } //1 dodaj.php?
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=103
 
}