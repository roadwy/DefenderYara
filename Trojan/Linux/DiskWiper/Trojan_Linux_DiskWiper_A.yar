
rule Trojan_Linux_DiskWiper_A{
	meta:
		description = "Trojan:Linux/DiskWiper.A,SIGNATURE_TYPE_CMDHSTR_EXT,3c 00 3c 00 06 00 00 "
		
	strings :
		$a_00_0 = {64 00 64 00 20 00 } //5 dd 
		$a_00_1 = {6f 00 66 00 3d 00 2f 00 64 00 65 00 76 00 2f 00 73 00 64 00 61 00 } //55 of=/dev/sda
		$a_00_2 = {6d 00 6b 00 69 00 6e 00 69 00 74 00 72 00 61 00 6d 00 66 00 73 00 } //-5 mkinitramfs
		$a_00_3 = {75 00 2d 00 62 00 6f 00 6f 00 74 00 2e 00 69 00 6d 00 78 00 } //-5 u-boot.imx
		$a_00_4 = {2e 00 69 00 73 00 6f 00 } //-5 .iso
		$a_00_5 = {2e 00 69 00 6d 00 67 00 } //-5 .img
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*55+(#a_00_2  & 1)*-5+(#a_00_3  & 1)*-5+(#a_00_4  & 1)*-5+(#a_00_5  & 1)*-5) >=60
 
}