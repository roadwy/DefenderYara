
rule Ransom_Win32_NopName_AMTB{
	meta:
		description = "Ransom:Win32/NopName!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {40 3d 3d 3d 3d 3d 3d 3d 3d 20 59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 4e 6f 70 4e 61 6d 65 20 3d 3d 3d 3d 3d 3d 3d 3d } //@======== You have been encrypted by NopName ========  2
		$a_80_1 = {40 2e 72 61 6d 73 30 6e } //@.rams0n  2
		$a_80_2 = {40 52 45 41 44 4d 45 2e 74 78 74 } //@README.txt  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}