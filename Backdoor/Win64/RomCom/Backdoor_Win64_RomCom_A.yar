
rule Backdoor_Win64_RomCom_A{
	meta:
		description = "Backdoor:Win64/RomCom.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 52 49 56 45 5f 4e 4f 5f 52 4f 4f 54 5f 44 49 52 20 2d 20 25 73 } //1 DRIVE_NO_ROOT_DIR - %s
		$a_01_1 = {53 43 52 45 45 4e 53 48 4f 4f 54 45 52 20 75 70 6c 6f 61 64 65 64 20 74 6f 20 63 6c 69 65 6e 74 } //1 SCREENSHOOTER uploaded to client
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 77 6f 72 6b 65 72 2e 74 78 74 } //1 C:\ProgramData\worker.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}