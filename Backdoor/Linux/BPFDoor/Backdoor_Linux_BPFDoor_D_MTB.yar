
rule Backdoor_Linux_BPFDoor_D_MTB{
	meta:
		description = "Backdoor:Linux/BPFDoor.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 76 61 72 2f 72 75 6e 2f 68 61 6c 64 72 75 6e 64 2e 70 69 64 } //1 /var/run/haldrund.pid
		$a_03_1 = {9d e3 bf 80 f0 27 a0 44 03 12 42 82 82 10 60 3c c2 27 bf e0 c0 27 bf e4 03 12 42 82 82 10 60 3c c2 27 bf 90 01 01 c0 27 bf 90 01 01 82 07 bf e0 d0 07 a0 44 92 10 00 01 90 00 } //2
		$a_03_2 = {9d e3 bf 78 f0 27 a0 44 03 00 00 4e 82 10 60 67 9a 90 01 03 98 10 20 16 90 90 10 00 0d 92 10 00 01 94 10 00 0c 40 90 02 05 01 00 00 00 40 90 02 05 01 00 00 00 9a 10 00 08 03 00 00 91 82 10 61 c4 c2 00 40 00 80 a3 40 01 90 02 05 01 00 00 00 82 90 01 03 90 90 10 00 01 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=5
 
}