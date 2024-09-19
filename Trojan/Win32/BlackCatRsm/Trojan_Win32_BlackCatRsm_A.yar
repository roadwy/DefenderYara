
rule Trojan_Win32_BlackCatRsm_A{
	meta:
		description = "Trojan:Win32/BlackCatRsm.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {2d 2d 6e 6f 2d 70 72 6f 70 2d 73 65 72 76 65 72 73 } //--no-prop-servers  1
		$a_80_1 = {2d 2d 6e 6f 2d 76 6d 2d 73 6e 61 70 73 68 6f 74 2d 6b 69 6c 6c } //--no-vm-snapshot-kill  1
		$a_80_2 = {64 72 6f 70 2d 64 72 61 67 90 02 50 64 72 6f 70 2d 74 61 72 67 65 74 90 00 } //drop-drag�Pdrop-target�  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=2
 
}