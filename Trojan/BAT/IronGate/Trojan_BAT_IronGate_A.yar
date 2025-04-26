
rule Trojan_BAT_IronGate_A{
	meta:
		description = "Trojan:BAT/IronGate.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 55 73 65 72 73 5c 4d 61 69 6e 5c 44 65 73 6b 74 6f 70 5c 53 74 65 70 37 50 72 6f 53 69 6d 50 72 6f 78 79 5c 53 74 65 70 37 50 72 6f 53 69 6d 50 72 6f 78 79 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 74 65 70 37 50 72 6f 53 69 6d 2e 70 64 62 } //1 c:\Users\Main\Desktop\Step7ProSimProxy\Step7ProSimProxy\obj\Release\Step7ProSim.pdb
		$a_01_1 = {24 38 36 33 64 38 61 66 30 2d 63 65 65 36 2d 34 36 37 36 2d 39 36 61 64 2d 31 33 65 38 35 34 30 66 34 64 34 37 } //1 $863d8af0-cee6-4676-96ad-13e8540f4d47
		$a_01_2 = {3c 46 69 6e 64 46 69 6c 65 49 6e 44 72 69 76 65 3e 62 5f 5f 33 } //1 <FindFileInDrive>b__3
		$a_00_3 = {62 00 69 00 6f 00 67 00 61 00 73 00 2e 00 65 00 78 00 65 00 } //1 biogas.exe
		$a_00_4 = {4b 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 20 00 72 00 65 00 6c 00 65 00 76 00 61 00 6e 00 74 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 73 00 2e 00 2e 00 2e 00 } //1 Killing relevant processes...
		$a_01_5 = {24 63 63 63 36 34 62 63 35 2d 65 66 39 35 2d 34 32 31 37 2d 61 64 63 34 2d 35 62 66 30 64 34 34 38 63 32 37 32 } //1 $ccc64bc5-ef95-4217-adc4-5bf0d448c272
		$a_00_6 = {63 3a 5c 55 73 65 72 73 5c 4d 61 69 6e 5c 44 65 73 6b 74 6f 70 5c 50 61 63 6b 61 67 69 6e 67 4d 6f 64 75 6c 65 5c 50 61 63 6b 61 67 69 6e 67 4d 6f 64 75 6c 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 50 61 63 6b 61 67 69 6e 67 4d 6f 64 75 6c 65 2e 70 64 62 } //1 c:\Users\Main\Desktop\PackagingModule\PackagingModule\obj\Release\PackagingModule.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}