
rule Trojan_Win64_DiskDestroyer_A_MTB{
	meta:
		description = "Trojan:Win64/DiskDestroyer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 } //2 \.\PhysicalDrive
		$a_01_1 = {57 72 69 74 65 20 44 69 73 6b 20 53 75 63 65 73 73 } //2 Write Disk Sucess
		$a_01_2 = {79 6f 75 72 20 64 61 74 61 20 69 6e 20 44 69 73 6b 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //2 your data in Disk has been encrypted
		$a_01_3 = {59 6f 75 72 20 50 43 20 68 61 73 20 62 65 65 6e 20 64 65 73 74 72 6f 79 65 64 20 62 79 } //2 Your PC has been destroyed by
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}