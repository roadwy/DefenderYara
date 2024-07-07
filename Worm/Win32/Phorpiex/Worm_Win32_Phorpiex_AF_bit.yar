
rule Worm_Win32_Phorpiex_AF_bit{
	meta:
		description = "Worm:Win32/Phorpiex.AF!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 74 6c 64 72 2e 70 68 70 3f 6e 65 77 3d 31 } //1 %stldr.php?new=1
		$a_01_1 = {25 73 74 6c 64 72 2e 70 68 70 3f 6f 6e 3d 31 } //1 %stldr.php?on=1
		$a_01_2 = {5c 00 77 00 69 00 6e 00 73 00 76 00 63 00 73 00 2e 00 74 00 78 00 74 00 } //1 \winsvcs.txt
		$a_01_3 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 5f 00 20 00 26 00 20 00 5f 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //1 /c start _ & _\DeviceManager.exe & exit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}