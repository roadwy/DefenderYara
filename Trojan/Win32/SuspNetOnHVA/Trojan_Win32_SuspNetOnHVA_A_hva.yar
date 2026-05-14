
rule Trojan_Win32_SuspNetOnHVA_A_hva{
	meta:
		description = "Trojan:Win32/SuspNetOnHVA.A!hva,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 } //1 \net.exe
		$a_00_1 = {5c 00 6e 00 65 00 74 00 31 00 2e 00 65 00 78 00 65 00 } //1 \net1.exe
		$a_00_2 = {2f 00 61 00 64 00 64 00 } //10 /add
		$a_00_3 = {67 00 72 00 6f 00 75 00 70 00 20 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 61 00 64 00 6d 00 69 00 6e 00 73 00 } //10 group domain admins
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=21
 
}