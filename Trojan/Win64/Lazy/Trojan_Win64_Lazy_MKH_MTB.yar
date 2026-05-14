
rule Trojan_Win64_Lazy_MKH_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 68 75 74 64 6f 77 6e 20 2d 66 20 2d 73 20 2d 74 20 31 30 20 2d 63 20 22 54 68 65 20 63 6f 6d 70 75 74 65 72 20 77 69 6c 6c 20 62 65 20 66 6f 72 63 69 62 6c 79 20 73 68 75 74 20 64 6f 77 6e 20 69 6e 20 36 30 20 73 65 63 6f 6e 64 73 } //10 shutdown -f -s -t 10 -c "The computer will be forcibly shut down in 60 seconds
		$a_01_1 = {74 61 73 6b 20 6d 61 6e 61 67 65 72 20 68 61 73 20 62 65 65 6e 20 66 6f 72 62 69 64 64 65 6e } //10 task manager has been forbidden
		$a_81_2 = {44 65 73 74 72 6f 79 20 64 72 69 76 65 20 6c 65 74 74 65 72 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //10 Destroy drive letter successfully!
		$a_81_3 = {68 61 63 6b 65 64 2e 6a 70 67 } //10 hacked.jpg
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //5 DisableTaskMgr
		$a_81_5 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //5 DisableRegistryTools
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5) >=50
 
}