
rule Trojan_Win64_VoidStealer_APSB_MTB{
	meta:
		description = "Trojan:Win64/VoidStealer.APSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 8b 4c 24 20 8b 15 ?? ?? ?? ?? ff c1 8b 05 ?? ?? ?? ?? d3 e2 33 c2 89 05 ?? ?? ?? ?? 8b 44 24 20 ff c0 89 44 24 20 8b 44 24 20 83 f8 03 7c } //4
		$a_81_1 = {56 4d 77 61 72 65 20 54 6f 6f 6c 73 } //1 VMware Tools
		$a_81_2 = {56 69 72 74 75 61 6c 42 6f 78 20 47 75 65 73 74 20 41 64 64 69 74 69 6f 6e 73 } //1 VirtualBox Guest Additions
		$a_81_3 = {5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 76 6d 68 67 66 73 } //1 \CurrentControlSet\Services\vmhgfs
	condition:
		((#a_03_0  & 1)*4+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=7
 
}