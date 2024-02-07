
rule Backdoor_Win32_Hupigon_A{
	meta:
		description = "Backdoor:Win32/Hupigon.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 5a 78 74 31 5a 33 40 33 42 65 78 52 6e 29 75 3a 2d 47 6a 3c 2a 6c 67 4f 35 79 35 3d 33 29 } //01 00  IZxt1Z3@3BexRn)u:-Gj<*lgO5y5=3)
		$a_01_1 = {36 00 64 00 39 00 32 00 61 00 44 00 61 00 4e 00 41 00 72 00 31 00 69 00 } //00 00  6d92aDaNAr1i
	condition:
		any of ($a_*)
 
}