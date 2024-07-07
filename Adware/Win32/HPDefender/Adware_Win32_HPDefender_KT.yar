
rule Adware_Win32_HPDefender_KT{
	meta:
		description = "Adware:Win32/HPDefender.KT,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 70 72 6f 6a 65 63 74 73 5c 6e 65 77 5f 43 6c 69 63 6b 65 72 5c 53 49 56 5c 6f 72 69 67 69 6e 61 6c 5c 64 61 65 6d 6f 6e 5c 4e 65 77 43 6c 69 65 63 6b 65 72 44 6c 6c 5c 52 65 6c 65 61 73 65 5c 53 49 56 55 70 64 61 74 65 2e 70 64 62 } //2 D:\projects\new_Clicker\SIV\original\daemon\NewClieckerDll\Release\SIVUpdate.pdb
	condition:
		((#a_01_0  & 1)*2) >=2
 
}