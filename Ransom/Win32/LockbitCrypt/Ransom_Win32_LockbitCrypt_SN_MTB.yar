
rule Ransom_Win32_LockbitCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/LockbitCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 ff d7 55 55 55 55 55 55 ff d3 81 fe 90 01 04 7e 90 01 01 81 7c 24 90 01 05 74 90 01 01 81 7c 24 90 01 05 75 90 01 01 46 8b c6 99 83 fa 01 7c 90 01 01 7f 90 01 01 3d 90 01 04 72 90 00 } //2
		$a_02_1 = {52 6a 40 51 50 ff 15 90 01 04 e8 90 01 04 8b 35 90 01 04 8b 3d 90 01 04 bb 90 01 04 eb 90 01 01 8d 49 00 81 3d 90 01 08 75 90 01 01 55 55 ff d6 55 ff d7 4b 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}