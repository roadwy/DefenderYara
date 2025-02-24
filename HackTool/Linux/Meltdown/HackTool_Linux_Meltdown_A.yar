
rule HackTool_Linux_Meltdown_A{
	meta:
		description = "HackTool:Linux/Meltdown.A,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {73 75 64 6f 20 73 68 20 2d 63 20 22 65 63 68 6f 20 30 20 20 3e 20 2f 70 72 6f 63 2f 73 79 73 2f 6b 65 72 6e 65 6c 2f 6b 70 74 72 5f 72 65 73 74 72 69 63 } //sudo sh -c "echo 0  > /proc/sys/kernel/kptr_restric  1
		$a_80_1 = {43 68 65 63 6b 69 6e 67 20 77 68 65 74 68 65 72 20 73 79 73 74 65 6d 20 69 73 20 61 66 66 65 63 74 65 64 20 62 79 20 56 61 72 69 61 6e 74 20 33 3a 20 72 6f 67 75 65 20 64 61 74 61 20 63 61 63 68 65 20 6c 6f 61 64 20 28 43 56 45 2d 32 30 31 37 2d 35 37 35 34 29 2c 20 61 2e 6b 2e 61 20 4d 45 4c 54 44 4f 57 4e } //Checking whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}