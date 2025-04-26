
rule Backdoor_Linux_Mirai_AN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {77 67 65 74 20 2d 67 20 [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 20 2d 6c 20 2f 74 6d 70 2f 63 30 6d 33 20 2d 72 } //1
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f 63 30 6d 33 3b 20 2f 74 6d 70 2f 63 30 6d 33 20 68 75 61 77 65 69 2e 65 78 70 6c 6f 69 74 } //2 /bin/busybox chmod 777 * /tmp/c0m3; /tmp/c0m3 huawei.exploit
		$a_00_2 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 20 30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 45 72 53 } //2 Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS
		$a_00_3 = {63 6e 63 2e 70 6f 70 73 6f 63 6b 65 74 73 6c 69 76 65 2e 63 6f 6d } //1 cnc.popsocketslive.com
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=3
 
}