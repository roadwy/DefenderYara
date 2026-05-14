
rule Ransom_Linux_LockBit_J_MSR{
	meta:
		description = "Ransom:Linux/LockBit.J!MSR,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 49 4e 46 4f 5d 20 56 4d 20 25 73 20 28 49 44 3a 20 25 64 29 20 69 6e 20 62 79 70 61 73 73 20 6c 69 73 74 2c 20 73 6b 69 70 70 69 6e 67 } //1 [INFO] VM %s (ID: %d) in bypass list, skipping
		$a_01_1 = {2f 62 69 6e 2f 76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 70 6f 77 65 72 2e 6f 66 66 20 25 64 } //1 /bin/vim-cmd vmsvc/power.off %d
		$a_01_2 = {2f 62 69 6e 2f 76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 70 6f 77 65 72 2e 67 65 74 73 74 61 74 65 20 25 64 } //1 /bin/vim-cmd vmsvc/power.getstate %d
		$a_01_3 = {45 6e 63 72 79 70 74 20 35 30 25 25 20 6f 66 20 65 61 63 68 20 66 69 6c 65 2c 20 73 6b 69 70 20 2f 74 6d 70 20 61 6e 64 20 2f 76 61 72 2f 6c 6f 67 } //1 Encrypt 50%% of each file, skip /tmp and /var/log
		$a_01_4 = {2f 62 69 6e 2f 76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 67 65 74 61 6c 6c 76 6d 73 } //1 /bin/vim-cmd vmsvc/getallvms
		$a_01_5 = {4c 49 4e 55 58 20 4c 6f 63 6b 65 72 20 76 31 2e 30 37 } //1 LINUX Locker v1.07
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}