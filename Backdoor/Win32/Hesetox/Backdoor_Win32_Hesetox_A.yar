
rule Backdoor_Win32_Hesetox_A{
	meta:
		description = "Backdoor:Win32/Hesetox.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 3b 3f 5b 33 2d 39 5d 7b 31 7d 5b 30 2d 39 5d 7b 31 32 2c 31 39 7d 5b 44 3d 5c 75 30 30 36 31 5d 5b 30 2d 39 5d 7b 31 30 2c 33 30 7d 5c 3f 3f } //1 \;?[3-9]{1}[0-9]{12,19}[D=\u0061][0-9]{10,30}\??
		$a_03_1 = {75 0f 6a 00 56 56 6a 00 ff d7 33 f6 56 ff d3 eb 02 33 f6 8d 45 90 01 01 50 68 02 02 00 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}