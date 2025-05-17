/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/zex_asset_manager.json`.
 */
export type ZexAssetManager = {
  "address": "CVtFHhvpcXSxAhcmkwtSozQogJonYMZoC9m4BjB1pm3u",
  "metadata": {
    "name": "zexAssetManager",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "Created with Anchor"
  },
  "instructions": [
    {
      "name": "adminAdd",
      "discriminator": [
        86,
        166,
        184,
        44,
        204,
        128,
        167,
        74
      ],
      "accounts": [
        {
          "name": "configs",
          "writable": true
        },
        {
          "name": "admin",
          "signer": true
        }
      ],
      "args": [
        {
          "name": "newAdmin",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "adminDelete",
      "discriminator": [
        0,
        117,
        153,
        137,
        221,
        77,
        158,
        16
      ],
      "accounts": [
        {
          "name": "configs",
          "writable": true
        },
        {
          "name": "admin",
          "signer": true
        }
      ],
      "args": [
        {
          "name": "adminToRemove",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "initialize",
      "discriminator": [
        175,
        175,
        109,
        31,
        13,
        152,
        155,
        237
      ],
      "accounts": [
        {
          "name": "configs",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  97,
                  115,
                  115,
                  101,
                  116,
                  109,
                  97,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103,
                  115
                ]
              }
            ]
          }
        },
        {
          "name": "admin",
          "writable": true,
          "signer": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "withdrawAuthor",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "resetWithdrawSolId",
      "discriminator": [
        56,
        75,
        235,
        216,
        224,
        117,
        83,
        10
      ],
      "accounts": [
        {
          "name": "admin",
          "writable": true,
          "signer": true
        },
        {
          "name": "withdrawIdRecord",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  119,
                  105,
                  116,
                  104,
                  100,
                  114,
                  97,
                  119,
                  45,
                  105,
                  100
                ]
              },
              {
                "kind": "arg",
                "path": "withdrawId"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": []
    },
    {
      "name": "setWithdrawAuthority",
      "discriminator": [
        199,
        146,
        140,
        67,
        1,
        90,
        8,
        222
      ],
      "accounts": [
        {
          "name": "configs",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  97,
                  115,
                  115,
                  101,
                  116,
                  109,
                  97,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103,
                  115
                ]
              }
            ]
          }
        },
        {
          "name": "admin",
          "writable": true,
          "signer": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "withdrawAuthor",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "transferSolToMainVault",
      "discriminator": [
        242,
        110,
        106,
        31,
        246,
        236,
        26,
        242
      ],
      "accounts": [
        {
          "name": "userVault",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  117,
                  115,
                  101,
                  114,
                  45,
                  118,
                  97,
                  117,
                  108,
                  116
                ]
              },
              {
                "kind": "arg",
                "path": "salt"
              }
            ]
          }
        },
        {
          "name": "mainVault",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  109,
                  97,
                  105,
                  110,
                  45,
                  118,
                  97,
                  117,
                  108,
                  116
                ]
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "salt",
          "type": "u64"
        }
      ]
    },
    {
      "name": "transferSplToMainVault",
      "discriminator": [
        224,
        143,
        78,
        247,
        104,
        140,
        216,
        42
      ],
      "accounts": [
        {
          "name": "signer",
          "writable": true,
          "signer": true
        },
        {
          "name": "userVault",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  117,
                  115,
                  101,
                  114,
                  45,
                  118,
                  97,
                  117,
                  108,
                  116
                ]
              },
              {
                "kind": "arg",
                "path": "salt"
              }
            ]
          }
        },
        {
          "name": "mainVault",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  109,
                  97,
                  105,
                  110,
                  45,
                  118,
                  97,
                  117,
                  108,
                  116
                ]
              }
            ]
          }
        },
        {
          "name": "userTokenAccount",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "path": "userVault"
              },
              {
                "kind": "const",
                "value": [
                  6,
                  221,
                  246,
                  225,
                  215,
                  101,
                  161,
                  147,
                  217,
                  203,
                  225,
                  70,
                  206,
                  235,
                  121,
                  172,
                  28,
                  180,
                  133,
                  237,
                  95,
                  91,
                  55,
                  145,
                  58,
                  140,
                  245,
                  133,
                  126,
                  255,
                  0,
                  169
                ]
              },
              {
                "kind": "account",
                "path": "mint"
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                140,
                151,
                37,
                143,
                78,
                36,
                137,
                241,
                187,
                61,
                16,
                41,
                20,
                142,
                13,
                131,
                11,
                90,
                19,
                153,
                218,
                255,
                16,
                132,
                4,
                142,
                123,
                216,
                219,
                233,
                248,
                89
              ]
            }
          }
        },
        {
          "name": "mainVaultTokenAccount",
          "writable": true
        },
        {
          "name": "mint",
          "writable": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        },
        {
          "name": "tokenProgram",
          "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        },
        {
          "name": "associatedTokenProgram",
          "address": "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        }
      ],
      "args": [
        {
          "name": "salt",
          "type": "u64"
        }
      ]
    },
    {
      "name": "withdrawSol",
      "discriminator": [
        145,
        131,
        74,
        136,
        65,
        137,
        42,
        38
      ],
      "accounts": [
        {
          "name": "configs",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  97,
                  115,
                  115,
                  101,
                  116,
                  109,
                  97,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103,
                  115
                ]
              }
            ]
          }
        },
        {
          "name": "mainVault",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  109,
                  97,
                  105,
                  110,
                  45,
                  118,
                  97,
                  117,
                  108,
                  116
                ]
              }
            ]
          }
        },
        {
          "name": "destination",
          "writable": true
        },
        {
          "name": "instructions"
        },
        {
          "name": "withdrawIdRecord",
          "docs": [
            "init_if_needed change to init in mainnet"
          ],
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  119,
                  105,
                  116,
                  104,
                  100,
                  114,
                  97,
                  119,
                  45,
                  105,
                  100
                ]
              },
              {
                "kind": "arg",
                "path": "withdrawId"
              }
            ]
          }
        },
        {
          "name": "signer",
          "writable": true,
          "signer": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "amount",
          "type": "u64"
        },
        {
          "name": "withdrawId",
          "type": "u64"
        },
        {
          "name": "signature",
          "type": {
            "array": [
              "u8",
              64
            ]
          }
        }
      ]
    },
    {
      "name": "withdrawSpl",
      "discriminator": [
        181,
        154,
        94,
        86,
        62,
        115,
        6,
        186
      ],
      "accounts": [
        {
          "name": "signer",
          "writable": true,
          "signer": true
        },
        {
          "name": "configs",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  97,
                  115,
                  115,
                  101,
                  116,
                  109,
                  97,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103,
                  115
                ]
              }
            ]
          }
        },
        {
          "name": "mainVault",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  109,
                  97,
                  105,
                  110,
                  45,
                  118,
                  97,
                  117,
                  108,
                  116
                ]
              }
            ]
          }
        },
        {
          "name": "mainVaultTokenAccount",
          "writable": true
        },
        {
          "name": "destination"
        },
        {
          "name": "destinationTokenAccount",
          "writable": true
        },
        {
          "name": "mint"
        },
        {
          "name": "instructions"
        },
        {
          "name": "withdrawIdRecord",
          "docs": [
            "init_if_needed change to init in mainnet"
          ],
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  119,
                  105,
                  116,
                  104,
                  100,
                  114,
                  97,
                  119,
                  45,
                  105,
                  100
                ]
              },
              {
                "kind": "arg",
                "path": "withdrawId"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        },
        {
          "name": "tokenProgram",
          "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        },
        {
          "name": "associatedTokenProgram",
          "address": "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        }
      ],
      "args": [
        {
          "name": "amount",
          "type": "u64"
        },
        {
          "name": "withdrawId",
          "type": "u64"
        },
        {
          "name": "signature",
          "type": {
            "array": [
              "u8",
              64
            ]
          }
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "configs",
      "discriminator": [
        147,
        170,
        81,
        90,
        28,
        157,
        218,
        71
      ]
    },
    {
      "name": "withdrawIdRecord",
      "discriminator": [
        168,
        214,
        201,
        191,
        128,
        45,
        20,
        231
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "adminRestricted",
      "msg": "Admin restricted method"
    },
    {
      "code": 6001,
      "name": "duplicateError",
      "msg": "Duplicate entry"
    },
    {
      "code": 6002,
      "name": "emptyAdmin",
      "msg": "No admin available"
    },
    {
      "code": 6003,
      "name": "unauthorized",
      "msg": "Unauthorized access"
    },
    {
      "code": 6004,
      "name": "missingData",
      "msg": "Missing data"
    },
    {
      "code": 6005,
      "name": "verifyFirst",
      "msg": "Verify first."
    },
    {
      "code": 6006,
      "name": "insufficientFunds",
      "msg": "Insufficient funds."
    },
    {
      "code": 6007,
      "name": "invalidMint",
      "msg": "Invalid mint."
    },
    {
      "code": 6008,
      "name": "mintMismatch",
      "msg": "Mint mismatch."
    }
  ],
  "types": [
    {
      "name": "configs",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "admins",
            "type": {
              "vec": "pubkey"
            }
          },
          {
            "name": "withdrawAuthor",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "withdrawIdRecord",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "used",
            "type": "bool"
          }
        ]
      }
    }
  ]
};
