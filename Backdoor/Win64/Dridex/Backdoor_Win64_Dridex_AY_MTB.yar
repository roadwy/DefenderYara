
rule Backdoor_Win64_Dridex_AY_MTB{
	meta:
		description = "Backdoor:Win64/Dridex.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 "
		
	strings :
		$a_00_0 = {ba 57 96 51 8f a1 af dc 1b d0 88 e1 8d f6 93 99 cf a9 c7 9c f0 46 d7 78 bf 47 d9 9b ca fb d1 15 } //10
		$a_00_1 = {7a 47 7d 30 28 54 39 59 48 3b 53 76 57 5d 25 71 2c 61 2f 41 72 31 68 2b 7b 2a 7c 29 77 70 72 47 45 3c 6d 3d 4a 66 76 25 3d } //10 zG}0(T9YH;SvW]%q,a/Ar1h+{*|)wprGE<m=Jfv%=
		$a_80_2 = {4d 70 72 43 6f 6e 66 69 67 47 65 74 46 72 69 65 6e 64 6c 79 4e 61 6d 65 } //MprConfigGetFriendlyName  3
		$a_80_3 = {4d 70 72 41 64 6d 69 6e 49 6e 74 65 72 66 61 63 65 53 65 74 49 6e 66 6f } //MprAdminInterfaceSetInfo  3
		$a_80_4 = {4d 70 72 43 6f 6e 66 69 67 53 65 72 76 65 72 44 69 73 63 6f 6e 6e 65 63 74 } //MprConfigServerDisconnect  3
		$a_80_5 = {4d 70 72 41 64 6d 69 6e 55 73 65 72 47 65 74 49 6e 66 6f } //MprAdminUserGetInfo  3
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=32
 
}